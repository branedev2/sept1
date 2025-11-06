import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.lang.reflect.Method;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringEscapeUtils;
import groovy.lang.GroovyShell;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import freemarker.template.Template;
import freemarker.template.Configuration;
import freemarker.template.TemplateException;
import org.python.util.PythonInterpreter;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import java.util.ArrayList;
import java.util.List;

@Controller
public class CodeInjectionExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("code");
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        try {
            // ruleid: java-code-injection
            engine.eval(userInput);
        } catch (ScriptException e) {
            response.getWriter().write("Error executing script: " + e.getMessage());
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String className = request.getParameter("class");
        String methodName = request.getParameter("method");
        
        try {
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            // ruleid: java-code-injection
            Method method = clazz.getMethod(methodName);
            method.invoke(instance);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String script = request.getParameter("groovyScript");
        GroovyShell shell = new GroovyShell();
        try {
            // ruleid: java-code-injection
            Object result = shell.evaluate(script);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @RequestMapping("/template")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String templateContent = request.getParameter("template");
        
        try {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_30);
            Template template = new Template("name", templateContent, cfg);
            Map<String, Object> root = new HashMap<>();
            root.put("user", "World");
            StringWriter out = new StringWriter();
            // ruleid: java-code-injection
            template.process(root, out);
            response.getWriter().write(out.toString());
        } catch (TemplateException e) {
            response.getWriter().write("Template error: " + e.getMessage());
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String pythonCode = request.getParameter("pythonCode");
        try (PythonInterpreter pyInterp = new PythonInterpreter()) {
            // ruleid: java-code-injection
            pyInterp.exec(pythonCode);
            response.getWriter().write("Python code executed");
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @PostMapping("/rhino")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsCode = request.getParameter("jsCode");
        Context context = Context.enter();
        try {
            Scriptable scope = context.initStandardObjects();
            // ruleid: java-code-injection
            Object result = context.evaluateString(scope, jsCode, "JavaScript", 1, null);
            response.getWriter().write("Result: " + Context.toString(result));
        } finally {
            Context.exit();
        }
    }

    @GetMapping("/spel")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String spelExpression = request.getParameter("expression");
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        
        // ruleid: java-code-injection
        Object result = parser.parseExpression(spelExpression).getValue(context);
        response.getWriter().write("Result: " + result);
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String command = request.getParameter("command");
        try {
            // ruleid: java-code-injection
            Process process = Runtime.getRuntime().exec(command);
            response.getWriter().write("Command executed");
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @RequestMapping("/dynamic-class")
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String classCode = request.getParameter("javaCode");
        String className = request.getParameter("className");
        
        try {
            // Create a dynamic compiler and compile the code
            javax.tools.JavaCompiler compiler = javax.tools.ToolProvider.getSystemJavaCompiler();
            javax.tools.StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null);
            
            // This is simplified - in a real scenario, you'd write to a file first
            // ruleid: java-code-injection
            compiler.getTask(null, fileManager, null, null, null, null).call();
            
            // Load and use the compiled class
            Class<?> loadedClass = Class.forName(className);
            Object instance = loadedClass.newInstance();
            response.getWriter().write("Class loaded: " + instance);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String expression = request.getParameter("bshScript");
        try {
            bsh.Interpreter interpreter = new bsh.Interpreter();
            // ruleid: java-code-injection
            Object result = interpreter.eval(expression);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @PostMapping("/mvel")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String mvelExpression = request.getParameter("mvelExpr");
        Map<String, Object> vars = new HashMap<>();
        vars.put("name", "world");
        
        try {
            // ruleid: java-code-injection
            Object result = org.mvel2.MVEL.eval(mvelExpression, vars);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String header = request.getHeader("X-Custom-Script");
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("nashorn");
        try {
            // ruleid: java-code-injection
            engine.eval(header);
            response.getWriter().write("Script executed from header");
        } catch (ScriptException e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @GetMapping("/ognl")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String ognlExpression = request.getParameter("ognl");
        try {
            // ruleid: java-code-injection
            Object result = ognl.Ognl.getValue(ognlExpression, null);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookieValue = null;
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("scriptCookie".equals(cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        
        if (cookieValue != null) {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            try {
                // ruleid: java-code-injection
                engine.eval(cookieValue);
                response.getWriter().write("Script from cookie executed");
            } catch (ScriptException e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
    }

    @PostMapping("/dynamic-proxy")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String interfaceName = request.getParameter("interface");
        String methodImpl = request.getParameter("implementation");
        
        try {
            Class<?> interfaceClass = Class.forName(interfaceName);
            
            // Create a dynamic proxy that executes user-provided code
            Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                interfaceClass.getClassLoader(),
                new Class<?>[] { interfaceClass },
                new java.lang.reflect.InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        // ruleid: java-code-injection
                        ScriptEngineManager manager = new ScriptEngineManager();
                        ScriptEngine engine = manager.getEngineByName("JavaScript");
                        return engine.eval(methodImpl);
                    }
                }
            );
            
            response.getWriter().write("Dynamic proxy created: " + proxy);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("code");
        // ok: java-code-injection
        if (!Pattern.matches("^[0-9+\\-*/()\\s.]+$", userInput)) {
            response.getWriter().write("Invalid input");
            return;
        }
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        try {
            engine.eval(userInput);
        } catch (ScriptException e) {
            response.getWriter().write("Error executing script: " + e.getMessage());
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String methodName = request.getParameter("method");
        
        // ok: java-code-injection
        Map<String, String> allowedMethods = new HashMap<>();
        allowedMethods.put("getUsers", "getUsersMethod");
        allowedMethods.put("getProducts", "getProductsMethod");
        
        if (!allowedMethods.containsKey(methodName)) {
            response.getWriter().write("Method not allowed");
            return;
        }
        
        String actualMethodName = allowedMethods.get(methodName);
        try {
            Method method = this.getClass().getMethod(actualMethodName);
            method.invoke(this);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String script = request.getParameter("groovyScript");
        
        // ok: java-code-injection
        CompilerConfiguration config = new CompilerConfiguration();
        config.setScriptBaseClass("com.example.SecureBaseScript");
        GroovyShell shell = new GroovyShell(config);
        
        // Using a sandbox to restrict operations
        try {
            // Using predefined templates instead of direct evaluation
            if ("calculateTax".equals(script)) {
                Object result = shell.evaluate("return calculateTax(amount, rate)");
                response.getWriter().write("Result: " + result);
            } else if ("formatDate".equals(script)) {
                Object result = shell.evaluate("return formatDate(date, pattern)");
                response.getWriter().write("Result: " + result);
            } else {
                response.getWriter().write("Script not allowed");
            }
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @RequestMapping("/safe-template")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String templateName = request.getParameter("template");
        
        // ok: java-code-injection
        Map<String, String> allowedTemplates = new HashMap<>();
        allowedTemplates.put("welcome", "Welcome ${user}!");
        allowedTemplates.put("goodbye", "Goodbye ${user}, see you soon!");
        
        if (!allowedTemplates.containsKey(templateName)) {
            response.getWriter().write("Template not found");
            return;
        }
        
        String templateContent = allowedTemplates.get(templateName);
        
        try {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_30);
            Template template = new Template("name", templateContent, cfg);
            Map<String, Object> root = new HashMap<>();
            root.put("user", "World");
            StringWriter out = new StringWriter();
            template.process(root, out);
            response.getWriter().write(out.toString());
        } catch (TemplateException e) {
            response.getWriter().write("Template error: " + e.getMessage());
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String operation = request.getParameter("operation");
        
        // ok: java-code-injection
        Map<String, String> allowedOperations = new HashMap<>();
        allowedOperations.put("add", "x + y");
        allowedOperations.put("subtract", "x - y");
        allowedOperations.put("multiply", "x * y");
        
        if (!allowedOperations.containsKey(operation)) {
            response.getWriter().write("Operation not allowed");
            return;
        }
        
        try (PythonInterpreter pyInterp = new PythonInterpreter()) {
            pyInterp.set("x", 10);
            pyInterp.set("y", 5);
            pyInterp.exec("result = " + allowedOperations.get(operation));
            int result = (Integer) pyInterp.get("result").__tojava__(Integer.class);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @PostMapping("/safe-rhino")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String operation = request.getParameter("operation");
        int x = Integer.parseInt(request.getParameter("x"));
        int y = Integer.parseInt(request.getParameter("y"));
        
        // ok: java-code-injection
        Map<String, String> allowedOperations = new HashMap<>();
        allowedOperations.put("add", "x + y");
        allowedOperations.put("subtract", "x - y");
        allowedOperations.put("multiply", "x * y");
        
        if (!allowedOperations.containsKey(operation)) {
            response.getWriter().write("Operation not allowed");
            return;
        }
        
        Context context = Context.enter();
        try {
            Scriptable scope = context.initStandardObjects();
            scope.put("x", scope, x);
            scope.put("y", scope, y);
            Object result = context.evaluateString(scope, allowedOperations.get(operation), "JavaScript", 1, null);
            response.getWriter().write("Result: " + Context.toString(result));
        } finally {
            Context.exit();
        }
    }

    @GetMapping("/safe-spel")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String property = request.getParameter("property");
        
        // ok: java-code-injection
        List<String> allowedProperties = new ArrayList<>();
        allowedProperties.add("name");
        allowedProperties.add("age");
        allowedProperties.add("email");
        
        if (!allowedProperties.contains(property)) {
            response.getWriter().write("Property not allowed");
            return;
        }
        
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        
        // Create a user object with properties
        User user = new User("John Doe", 30, "john@example.com");
        context.setVariable("user", user);
        
        Object result = parser.parseExpression("#user." + property).getValue(context);
        response.getWriter().write("Result: " + result);
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String command = request.getParameter("command");
        
        // ok: java-code-injection
        List<String> allowedCommands = new ArrayList<>();
        allowedCommands.add("list-files");
        allowedCommands.add("check-disk-space");
        allowedCommands.add("check-memory");
        
        if (!allowedCommands.contains(command)) {
            response.getWriter().write("Command not allowed");
            return;
        }
        
        String actualCommand;
        switch (command) {
            case "list-files":
                actualCommand = "ls -l";
                break;
            case "check-disk-space":
                actualCommand = "df -h";
                break;
            case "check-memory":
                actualCommand = "free -m";
                break;
            default:
                response.getWriter().write("Invalid command");
                return;
        }
        
        try {
            Process process = Runtime.getRuntime().exec(actualCommand);
            response.getWriter().write("Command executed");
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @RequestMapping("/safe-class")
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String className = request.getParameter("className");
        
        // ok: java-code-injection
        Map<String, Class<?>> allowedClasses = new HashMap<>();
        allowedClasses.put("user", User.class);
        allowedClasses.put("product", Product.class);
        allowedClasses.put("order", Order.class);
        
        if (!allowedClasses.containsKey(className)) {
            response.getWriter().write("Class not allowed");
            return;
        }
        
        try {
            Class<?> clazz = allowedClasses.get(className);
            Object instance = clazz.newInstance();
            response.getWriter().write("Class instantiated: " + instance);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String expression = request.getParameter("bshScript");
        
        // ok: java-code-injection
        if (!expression.matches("^[a-zA-Z0-9+\\-*/()\\s.]+$")) {
            response.getWriter().write("Invalid expression");
            return;
        }
        
        try {
            bsh.Interpreter interpreter = new bsh.Interpreter();
            // Set strict Java mode to prevent access to system functions
            interpreter.eval("setStrictJava(true);");
            Object result = interpreter.eval(expression);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @PostMapping("/safe-mvel")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String template = request.getParameter("template");
        
        // ok: java-code-injection
        Map<String, String> allowedTemplates = new HashMap<>();
        allowedTemplates.put("greeting", "Hello @{name}!");
        allowedTemplates.put("farewell", "Goodbye @{name}!");
        
        if (!allowedTemplates.containsKey(template)) {
            response.getWriter().write("Template not allowed");
            return;
        }
        
        Map<String, Object> vars = new HashMap<>();
        vars.put("name", StringEscapeUtils.escapeHtml4(request.getParameter("name")));
        
        try {
            Object result = org.mvel2.templates.TemplateRuntime.eval(allowedTemplates.get(template), vars);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String header = request.getHeader("X-Custom-Script");
        
        // ok: java-code-injection
        Map<String, String> predefinedScripts = new HashMap<>();
        predefinedScripts.put("getUserInfo", "function getUserInfo() { return 'User Info'; }; getUserInfo();");
        predefinedScripts.put("getSystemStatus", "function getSystemStatus() { return 'System OK'; }; getSystemStatus();");
        
        if (!predefinedScripts.containsKey(header)) {
            response.getWriter().write("Script not allowed");
            return;
        }
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("nashorn");
        try {
            Object result = engine.eval(predefinedScripts.get(header));
            response.getWriter().write("Script result: " + result);
        } catch (ScriptException e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    @GetMapping("/safe-ognl")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String property = request.getParameter("property");
        
        // ok: java-code-injection
        List<String> allowedProperties = new ArrayList<>();
        allowedProperties.add("name");
        allowedProperties.add("age");
        allowedProperties.add("email");
        
        if (!allowedProperties.contains(property)) {
            response.getWriter().write("Property not allowed");
            return;
        }
        
        try {
            User user = new User("John Doe", 30, "john@example.com");
            Object result = ognl.Ognl.getValue(property, user);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookieValue = null;
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("scriptCookie".equals(cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        
        if (cookieValue != null) {
            // ok: java-code-injection
            // Validate cookie value against a whitelist
            Map<String, String> allowedScripts = new HashMap<>();
            allowedScripts.put("getDate", "new Date().toString()");
            allowedScripts.put("getTime", "new Date().getTime()");
            
            if (!allowedScripts.containsKey(cookieValue)) {
                response.getWriter().write("Script not allowed");
                return;
            }
            
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            try {
                Object result = engine.eval(allowedScripts.get(cookieValue));
                response.getWriter().write("Script result: " + result);
            } catch (ScriptException e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
    }

    @PostMapping("/safe-proxy")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String interfaceName = request.getParameter("interface");
        
        // ok: java-code-injection
        Map<String, Class<?>> allowedInterfaces = new HashMap<>();
        allowedInterfaces.put("calculator", Calculator.class);
        allowedInterfaces.put("formatter", Formatter.class);
        
        if (!allowedInterfaces.containsKey(interfaceName)) {
            response.getWriter().write("Interface not allowed");
            return;
        }
        
        Class<?> interfaceClass = allowedInterfaces.get(interfaceName);
        
        try {
            // Create a proxy with predefined implementations
            Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                interfaceClass.getClassLoader(),
                new Class<?>[] { interfaceClass },
                new java.lang.reflect.InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        // Safe implementation with predefined methods
                        if ("add".equals(method.getName())) {
                            return (int)args[0] + (int)args[1];
                        } else if ("subtract".equals(method.getName())) {
                            return (int)args[0] - (int)args[1];
                        } else if ("format".equals(method.getName())) {
                            return "Formatted: " + args[0];
                        }
                        return null;
                    }
                }
            );
            
            response.getWriter().write("Dynamic proxy created: " + proxy);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    // Helper classes
    private class User {
        private String name;
        private int age;
        private String email;
        
        public User(String name, int age, String email) {
            this.name = name;
            this.age = age;
            this.email = email;
        }
        
        public String getName() { return name; }
        public int getAge() { return age; }
        public String getEmail() { return email; }
    }
    
    private class Product {
        private String name;
        private double price;
        
        public Product() {
            this.name = "Default Product";
            this.price = 0.0;
        }
    }
    
    private class Order {
        private String id;
        private double total;
        
        public Order() {
            this.id = "DEFAULT-ORDER";
            this.total = 0.0;
        }
    }
    
    private interface Calculator {
        int add(int a, int b);
        int subtract(int a, int b);
    }
    
    private interface Formatter {
        String format(String input);
    }
    
    private String getUsersMethod() {
        return "User list";
    }
    
    private String getProductsMethod() {
        return "Product list";
    }
}
// {/fact}