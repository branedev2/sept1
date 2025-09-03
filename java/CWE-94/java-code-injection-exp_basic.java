import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import groovy.lang.GroovyShell;
import groovy.lang.Binding;
import bsh.Interpreter;
import javax.el.ELProcessor;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import java.util.Map;
import java.util.HashMap;

@Controller
public class CodeInjectionExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @RequestMapping("/bad1")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, ScriptException {
        String userScript = request.getParameter("script");
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        
        // ruleid: java-code-injection-exp
        engine.eval(userScript);
        
        response.getWriter().write("Script executed");
    }
    
    @RequestMapping("/bad2")
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userCode = request.getParameter("code");
        
        Context context = Context.enter();
        try {
            Scriptable scope = context.initStandardObjects();
            // ruleid: java-code-injection-exp
            Object result = context.evaluateString(scope, userCode, "DynamicCode", 1, null);
            response.getWriter().write("Result: " + result);
        } finally {
            Context.exit();
        }
    }
    
    @RequestMapping("/bad3")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userScript = request.getParameter("groovy");
        
        GroovyShell shell = new GroovyShell();
        // ruleid: java-code-injection-exp
        Object result = shell.evaluate(userScript);
        
        response.getWriter().write("Result: " + result);
    }
    
    @RequestMapping("/bad4")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userScript = request.getParameter("beanshell");
        
        try {
            Interpreter interpreter = new Interpreter();
            // ruleid: java-code-injection-exp
            interpreter.eval(userScript);
            response.getWriter().write("Script executed");
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    @RequestMapping("/bad5")
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userExpression = request.getParameter("el");
        
        ELProcessor processor = new ELProcessor();
        // ruleid: java-code-injection-exp
        Object result = processor.eval(userExpression);
        
        response.getWriter().write("Result: " + result);
    }
    
    @RequestMapping("/bad6")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, ScriptException {
        String script = request.getHeader("X-Script");
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        
        // ruleid: java-code-injection-exp
        engine.eval(script);
        
        response.getWriter().write("Script from header executed");
    }
    
    @RequestMapping("/bad7")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("input");
        String script = "print('" + userInput + "')";
        
        GroovyShell shell = new GroovyShell();
        // ruleid: java-code-injection-exp
        shell.evaluate(script);
        
        response.getWriter().write("Executed with user input");
    }
    
    @RequestMapping("/bad8")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, ScriptException {
        String userCode = request.getParameter("code");
        String processedCode = userCode.replace("badword", "");
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        
        // ruleid: java-code-injection-exp
        engine.eval(processedCode);
        
        response.getWriter().write("Processed script executed");
    }
    
    @RequestMapping("/bad9")
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        String script = sb.toString();
        
        try {
            Interpreter interpreter = new Interpreter();
            // ruleid: java-code-injection-exp
            interpreter.eval(script);
            response.getWriter().write("Script from request body executed");
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    @RequestMapping("/bad10")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] scripts = request.getParameterValues("scripts");
        
        if (scripts != null && scripts.length > 0) {
            GroovyShell shell = new GroovyShell();
            for (String script : scripts) {
                // ruleid: java-code-injection-exp
                shell.evaluate(script);
            }
        }
        
        response.getWriter().write("Multiple scripts executed");
    }
    
    @PostMapping("/bad11")
    public void bad_case_11(@RequestBody Map<String, String> payload, HttpServletResponse response) throws ServletException, IOException, ScriptException {
        String script = payload.get("script");
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        
        // ruleid: java-code-injection-exp
        Object result = engine.eval(script);
        
        response.getWriter().write("Result: " + result);
    }
    
    @RequestMapping("/bad12")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userScript = request.getParameter("script");
        
        Binding binding = new Binding();
        binding.setVariable("request", request);
        binding.setVariable("response", response);
        
        GroovyShell shell = new GroovyShell(binding);
        // ruleid: java-code-injection-exp
        shell.evaluate(userScript);
    }
    
    @RequestMapping("/bad13")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, ScriptException {
        String script = request.getParameter("script");
        if (script != null && !script.isEmpty()) {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            Map<String, Object> context = new HashMap<>();
            context.put("request", request);
            engine.getBindings(javax.script.ScriptContext.ENGINE_SCOPE).putAll(context);
            
            // ruleid: java-code-injection-exp
            engine.eval(script);
        }
    }
    
    @RequestMapping("/bad14")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userCode = request.getParameter("code");
        String sanitized = userCode.replaceAll("[^a-zA-Z0-9+\\-*/().]", "");
        
        try {
            // Even with some sanitization, this is still vulnerable
            Interpreter interpreter = new Interpreter();
            // ruleid: java-code-injection-exp
            Object result = interpreter.eval(sanitized);
            response.getWriter().write("Result: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    @RequestMapping("/bad15")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String expression = request.getParameter("expr");
        
        CompilerConfiguration config = new CompilerConfiguration();
        GroovyShell shell = new GroovyShell(config);
        
        try {
            // ruleid: java-code-injection-exp
            Object result = shell.evaluate(expression);
            response.getWriter().write("Evaluated: " + result);
        } catch (Exception e) {
            response.getWriter().write("Error evaluating expression");
        }
    }
    
    // True Negative Examples (Safe Code)
    
    @RequestMapping("/good1")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // Hardcoded script, not using user input for code execution
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        
        try {
            // ok: java-code-injection-exp
            engine.eval("var x = 10; var y = 20; x + y;");
            response.getWriter().write("Script executed safely");
        } catch (ScriptException e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    @RequestMapping("/good2")
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // Using user input as data, not as code
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        
        try {
            engine.put("userValue", userInput);
            // ok: java-code-injection-exp
            engine.eval("var result = 'Hello, ' + userValue;");
            response.getWriter().write("Script executed with user data");
        } catch (ScriptException e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    @RequestMapping("/good3")
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // Using a whitelist of allowed expressions
        String[] allowedExpressions = {"1+1", "2*2", "10/2"};
        boolean isAllowed = false;
        
        for (String expr : allowedExpressions) {
            if (expr.equals(userInput)) {
                isAllowed = true;
                break;
            }
        }
        
        if (isAllowed) {
            try {
                ScriptEngineManager manager = new ScriptEngineManager();
                ScriptEngine engine = manager.getEngineByName("JavaScript");
                // ok: java-code-injection-exp
                Object result = engine.eval(userInput);
                response.getWriter().write("Result: " + result);
            } catch (ScriptException e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        } else {
            response.getWriter().write("Expression not allowed");
        }
    }
    
    @RequestMapping("/good4")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String operation = request.getParameter("operation");
        String num1Str = request.getParameter("num1");
        String num2Str = request.getParameter("num2");
        
        // Parse and validate inputs
        double num1, num2, result = 0;
        try {
            num1 = Double.parseDouble(num1Str);
            num2 = Double.parseDouble(num2Str);
        } catch (NumberFormatException e) {
            response.getWriter().write("Invalid numbers");
            return;
        }
        
        // ok: java-code-injection-exp
        switch (operation) {
            case "add":
                result = num1 + num2;
                break;
            case "subtract":
                result = num1 - num2;
                break;
            case "multiply":
                result = num1 * num2;
                break;
            case "divide":
                if (num2 != 0) {
                    result = num1 / num2;
                } else {
                    response.getWriter().write("Cannot divide by zero");
                    return;
                }
                break;
            default:
                response.getWriter().write("Unknown operation");
                return;
        }
        
        response.getWriter().write("Result: " + result);
    }
    
    @RequestMapping("/good5")
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String template = request.getParameter("template");
        String name = request.getParameter("name");
        
        // Simple template system without code execution
        if (template != null && name != null) {
            // ok: java-code-injection-exp
            String result = template.replace("{{name}}", name);
            response.getWriter().write(result);
        } else {
            response.getWriter().write("Missing parameters");
        }
    }
    
    @RequestMapping("/good6")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // Using regex pattern matching instead of code execution
        if (userInput != null) {
            // ok: java-code-injection-exp
            boolean isValid = Pattern.matches("[a-zA-Z0-9]+", userInput);
            response.getWriter().write("Input validation result: " + isValid);
        } else {
            response.getWriter().write("No input provided");
        }
    }
    
    @RequestMapping("/good7")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String expression = request.getParameter("expr");
        
        // Simple calculator with explicit parsing
        if (expression != null && !expression.isEmpty()) {
            try {
                // ok: java-code-injection-exp
                double result = evaluateExpression(expression);
                response.getWriter().write("Result: " + result);
            } catch (Exception e) {
                response.getWriter().write("Invalid expression");
            }
        } else {
            response.getWriter().write("No expression provided");
        }
    }
    
    private double evaluateExpression(String expr) {
        // A very simple expression evaluator for demonstration
        // In real code, you would use a proper expression parser
        String sanitized = expr.replaceAll("[^0-9+\\-*/().]", "");
        return Double.parseDouble(sanitized);
    }
    
    @RequestMapping("/good8")
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String script = request.getParameter("script");
        
        // Log the attempt but don't execute
        System.out.println("Attempted script execution: " + script);
        
        // ok: java-code-injection-exp
        response.getWriter().write("Script execution not allowed");
    }
    
    @RequestMapping("/good9")
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, ScriptException {
        // Using predefined scripts with user-provided parameters
        String operation = request.getParameter("operation");
        String valueStr = request.getParameter("value");
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        
        try {
            double value = Double.parseDouble(valueStr);
            engine.put("value", value);
            
            String script;
            switch (operation) {
                case "square":
                    script = "value * value";
                    break;
                case "double":
                    script = "value * 2";
                    break;
                case "half":
                    script = "value / 2";
                    break;
                default:
                    response.getWriter().write("Unknown operation");
                    return;
            }
            
            // ok: java-code-injection-exp
            Object result = engine.eval(script);
            response.getWriter().write("Result: " + result);
        } catch (NumberFormatException e) {
            response.getWriter().write("Invalid number");
        }
    }
    
    @RequestMapping("/good10")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // Process data without code execution
        Map<String, Object> context = new HashMap<>();
        context.put("userInput", userInput);
        
        // ok: java-code-injection-exp
        String output = processTemplate("Hello, ${userInput}!", context);
        response.getWriter().write(output);
    }
    
    private String processTemplate(String template, Map<String, Object> context) {
        // Simple template processor that doesn't use code execution
        for (Map.Entry<String, Object> entry : context.entrySet()) {
            String placeholder = "\\$\\{" + entry.getKey() + "\\}";
            template = template.replaceAll(placeholder, entry.getValue().toString());
        }
        return template;
    }
    
    @RequestMapping("/good11")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String code = request.getParameter("code");
        
        // Instead of executing code, validate against known patterns
        if (code != null) {
            // ok: java-code-injection-exp
            if (code.matches("^[a-zA-Z0-9_]+\\([0-9]+(,[0-9]+)*\\)$")) {
                response.getWriter().write("Valid function call pattern");
            } else {
                response.getWriter().write("Invalid function call pattern");
            }
        }
    }
    
    @RequestMapping("/good12")
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userScript = request.getParameter("script");
        
        // Simulate script execution with a mock response
        response.setContentType("application/json");
        
        // ok: java-code-injection-exp
        response.getWriter().write("{\"status\":\"success\",\"message\":\"Script execution simulated\"}");
    }
    
    @RequestMapping("/good13")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String expression = request.getParameter("expr");
        
        // Use a domain-specific language with limited capabilities
        if (expression != null) {
            try {
                // ok: java-code-injection-exp
                String result = evaluateDSL(expression);
                response.getWriter().write("Result: " + result);
            } catch (Exception e) {
                response.getWriter().write("Invalid expression: " + e.getMessage());
            }
        }
    }
    
    private String evaluateDSL(String expression) {
        // A very simple DSL interpreter that only supports basic operations
        // This is a placeholder for a real DSL implementation
        if (expression.equals("CURRENT_TIME")) {
            return String.valueOf(System.currentTimeMillis());
        } else if (expression.equals("SERVER_NAME")) {
            return "Example Server";
        } else {
            throw new IllegalArgumentException("Unknown DSL command");
        }
    }
    
    @RequestMapping("/good14")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // Use a configuration-based approach instead of dynamic code
        Map<String, String> allowedCommands = new HashMap<>();
        allowedCommands.put("greeting", "Hello, World!");
        allowedCommands.put("farewell", "Goodbye!");
        allowedCommands.put("welcome", "Welcome to our application!");
        
        // ok: java-code-injection-exp
        if (allowedCommands.containsKey(userInput)) {
            response.getWriter().write(allowedCommands.get(userInput));
        } else {
            response.getWriter().write("Unknown command");
        }
    }
    
    @RequestMapping("/good15")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String mathExpression = request.getParameter("math");
        
        if (mathExpression != null && !mathExpression.isEmpty()) {
            try {
                // Use a dedicated math expression evaluator instead of a general script engine
                // ok: java-code-injection-exp
                double result = evaluateMathExpression(mathExpression);
                response.getWriter().write("Result: " + result);
            } catch (Exception e) {
                response.getWriter().write("Invalid math expression");
            }
        }
    }
    
    private double evaluateMathExpression(String expr) {
        // This would be a specialized math expression evaluator
        // For demonstration, we're using a very simple implementation
        String sanitized = expr.replaceAll("[^0-9+\\-*/().]", "");
        if (!sanitized.equals(expr)) {
            throw new IllegalArgumentException("Invalid characters in expression");
        }
        
        // In a real implementation, you would use a proper math expression parser
        // This is just a placeholder
        return 42.0;
    }
}
// {/fact}