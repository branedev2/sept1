import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Map;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.jexl3.*;
import org.mvel2.MVEL;
import groovy.lang.GroovyShell;
import groovy.lang.Binding;
import org.codehaus.janino.ScriptEvaluator;
import bsh.Interpreter;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import org.python.util.PythonInterpreter;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.apache.commons.el.ExpressionEvaluatorImpl;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;
import javax.el.ELContext;
import org.apache.el.ExpressionFactoryImpl;
import org.apache.el.lang.ELSupport;
import com.googlecode.aviator.AviatorEvaluator;
import org.apache.commons.lang3.StringEscapeUtils;
import org.owasp.encoder.Encode;
import java.util.regex.Pattern;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.utils.URIBuilder;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.RequestBody;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import org.apache.commons.validator.routines.RegexValidator;

// Security Issue: Code Injection via dynamic code execution with user input

// True Positive Examples (Vulnerable/Insecure Code)
@Controller
public class CodeInjectionExamples {

    // Example 1: Using javax.script.ScriptEngine with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @RequestMapping("/bad1")
    public String bad_case_1(@RequestParam String userScript) {
        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            // ruleid: java-code-injection
            Object result = engine.eval(userScript);
            
            return "Result: " + result.toString();
        } catch (ScriptException e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 2: Using JEXL expression evaluation with user input
    @RequestMapping("/bad2")
    public String bad_case_2(HttpServletRequest request) {
        String userExpression = request.getParameter("expression");
        JexlEngine jexl = new JexlBuilder().create();
        
        // ruleid: java-code-injection
        JexlExpression expression = jexl.createExpression(userExpression);
        
        JexlContext context = new MapContext();
        Object result = expression.evaluate(context);
        return "Result: " + result.toString();
    }

    // Example 3: Using MVEL expression evaluation with user input
    @GetMapping("/bad3")
    public String bad_case_3(@RequestParam String mvelCode) {
        try {
            // ruleid: java-code-injection
            Object result = MVEL.eval(mvelCode);
            
            return "MVEL Result: " + result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 4: Using Groovy Shell with user input
    @PostMapping("/bad4")
    public String bad_case_4(@RequestBody String groovyCode) {
        GroovyShell shell = new GroovyShell();
        
        // ruleid: java-code-injection
        Object result = shell.evaluate(groovyCode);
        
        return "Groovy Result: " + result.toString();
    }

    // Example 5: Using Janino ScriptEvaluator with user input
    @GetMapping("/bad5")
    public String bad_case_5(HttpServletRequest request) {
        try {
            String userCode = request.getParameter("code");
            ScriptEvaluator evaluator = new ScriptEvaluator();
            evaluator.setReturnType(Object.class);
            
            // ruleid: java-code-injection
            Object result = evaluator.evaluate(userCode);
            
            return "Janino Result: " + result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 6: Using BeanShell Interpreter with user input
    @RequestMapping("/bad6")
    public String bad_case_6(@RequestParam String bshCode) {
        try {
            Interpreter interpreter = new Interpreter();
            
            // ruleid: java-code-injection
            Object result = interpreter.eval(bshCode);
            
            return "BeanShell Result: " + (result != null ? result.toString() : "null");
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 7: Using AWS Lambda with dynamic code
    @GetMapping("/bad7")
    public String bad_case_7(@RequestParam String functionCode) {
        AWSLambda awsLambda = AWSLambdaClientBuilder.defaultClient();
        InvokeRequest request = new InvokeRequest()
            .withFunctionName("dynamic-executor");
        
        // ruleid: java-code-injection
        request.withPayload("{\"code\":\"" + functionCode + "\"}");
        
        return "Lambda invoked";
    }

    // Example 8: Using Mozilla Rhino JavaScript engine with user input
    @PostMapping("/bad8")
    public String bad_case_8(@RequestBody String jsCode) {
        Context context = Context.enter();
        try {
            Scriptable scope = context.initStandardObjects();
            
            // ruleid: java-code-injection
            Object result = context.evaluateString(scope, jsCode, "DynamicScript", 1, null);
            
            return "Rhino Result: " + Context.toString(result);
        } finally {
            Context.exit();
        }
    }

    // Example 9: Using Jython with user input
    @GetMapping("/bad9")
    public String bad_case_9(HttpServletRequest request) {
        String pythonCode = request.getParameter("pycode");
        PythonInterpreter interpreter = new PythonInterpreter();
        
        // ruleid: java-code-injection
        interpreter.exec(pythonCode);
        
        return "Python code executed";
    }

    // Example 10: Using Spring Expression Language (SpEL) with user input
    @RequestMapping("/bad10")
    public String bad_case_10(@RequestParam String spelExpression) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        
        // ruleid: java-code-injection
        Expression exp = parser.parseExpression(spelExpression);
        
        Object result = exp.getValue(context);
        return "SpEL Result: " + result.toString();
    }

    // Example 11: Using Java EL with user input
    @GetMapping("/bad11")
    public String bad_case_11(HttpServletRequest request) {
        String elExpression = request.getParameter("el");
        ExpressionFactory factory = new ExpressionFactoryImpl();
        ELContext context = new javax.el.StandardELContext(factory);
        
        // ruleid: java-code-injection
        ValueExpression ve = factory.createValueExpression(context, elExpression, Object.class);
        
        Object result = ve.getValue(context);
        return "EL Result: " + result.toString();
    }

    // Example 12: Using Aviator Expression Engine with user input
    @PostMapping("/bad12")
    public String bad_case_12(@RequestBody Map<String, String> payload) {
        String expression = payload.get("expression");
        
        // ruleid: java-code-injection
        Object result = AviatorEvaluator.execute(expression);
        
        return "Aviator Result: " + result.toString();
    }

    // Example 13: Using Vertx with user input for dynamic evaluation
    public void bad_case_13() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/evaluate").handler(ctx -> {
            String code = ctx.request().getParam("code");
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            try {
                // ruleid: java-code-injection
                Object result = engine.eval(code);
                
                ctx.response().end("Result: " + result);
            } catch (Exception e) {
                ctx.response().end("Error: " + e.getMessage());
            }
        });
    }

    // Example 14: Using Jetty with user input for dynamic evaluation
    public static class bad_case_14 extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request,
                          HttpServletResponse response) throws IOException, ServletException {
            String code = request.getParameter("code");
            GroovyShell shell = new GroovyShell();
            
            response.setContentType("text/html;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            baseRequest.setHandled(true);
            
            try {
                // ruleid: java-code-injection
                Object result = shell.evaluate(code);
                
                response.getWriter().println("Result: " + result);
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    // Example 15: Using Apache Commons EL with user input
    @RequestMapping("/bad15")
    public String bad_case_15(@RequestParam String expression) {
        try {
            ExpressionEvaluatorImpl evaluator = new ExpressionEvaluatorImpl();
            
            // ruleid: java-code-injection
            Object result = evaluator.evaluate(expression, Object.class, null, null);
            
            return "Commons EL Result: " + result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    
    // Example 1: Using javax.script.ScriptEngine with validated input
    @RequestMapping("/good1")
    public String good_case_1(@RequestParam String userScript) {
        try {
            // Validate input against a whitelist of allowed expressions
            Pattern safePattern = Pattern.compile("^[0-9+\\-*/()\\s.]+$");
            if (!safePattern.matcher(userScript).matches()) {
                return "Invalid input: Only arithmetic expressions are allowed";
            }
            
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            // ok: java-code-injection
            Object result = engine.eval(userScript);
            
            return "Result: " + result.toString();
        } catch (ScriptException e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 2: Using JEXL with predefined templates and parameters
    @RequestMapping("/good2")
    public String good_case_2(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        String value1Param = request.getParameter("value1");
        String value2Param = request.getParameter("value2");
        
        // Validate operation parameter
        if (!operation.matches("add|subtract|multiply|divide")) {
            return "Invalid operation";
        }
        
        // Parse and validate numeric inputs
        double value1, value2;
        try {
            value1 = Double.parseDouble(value1Param);
            value2 = Double.parseDouble(value2Param);
        } catch (NumberFormatException e) {
            return "Invalid numeric input";
        }
        
        // Use predefined templates instead of user-provided expressions
        String template;
        switch (operation) {
            case "add": template = "value1 + value2"; break;
            case "subtract": template = "value1 - value2"; break;
            case "multiply": template = "value1 * value2"; break;
            case "divide": template = "value1 / value2"; break;
            default: return "Invalid operation";
        }
        
        JexlEngine jexl = new JexlBuilder().create();
        // ok: java-code-injection
        JexlExpression expression = jexl.createExpression(template);
        
        JexlContext context = new MapContext();
        context.set("value1", value1);
        context.set("value2", value2);
        
        Object result = expression.evaluate(context);
        return "Result: " + result.toString();
    }

    // Example 3: Using MVEL with predefined expressions and sanitized inputs
    @GetMapping("/good3")
    public String good_case_3(@RequestParam String operation, @RequestParam double x, @RequestParam double y) {
        Map<String, Object> vars = Map.of("x", x, "y", y);
        
        // Use a map of predefined expressions instead of user input
        Map<String, String> safeExpressions = Map.of(
            "add", "x + y",
            "subtract", "x - y",
            "multiply", "x * y",
            "divide", "x / y"
        );
        
        if (!safeExpressions.containsKey(operation)) {
            return "Invalid operation";
        }
        
        // ok: java-code-injection
        Object result = MVEL.eval(safeExpressions.get(operation), vars);
        
        return "MVEL Result: " + result.toString();
    }

    // Example 4: Using Groovy with parameter binding instead of direct code execution
    @PostMapping("/good4")
    public String good_case_4(@RequestBody Map<String, Object> params) {
        // Define a fixed script template with placeholders
        String scriptTemplate = "return x * y + z";
        
        // Validate input parameters
        if (!params.containsKey("x") || !params.containsKey("y") || !params.containsKey("z")) {
            return "Missing required parameters";
        }
        
        try {
            // Convert parameters to appropriate types
            double x = Double.parseDouble(params.get("x").toString());
            double y = Double.parseDouble(params.get("y").toString());
            double z = Double.parseDouble(params.get("z").toString());
            
            // Bind parameters to the script
            Binding binding = new Binding();
            binding.setVariable("x", x);
            binding.setVariable("y", y);
            binding.setVariable("z", z);
            
            GroovyShell shell = new GroovyShell(binding);
            
            // ok: java-code-injection
            Object result = shell.evaluate(scriptTemplate);
            
            return "Groovy Result: " + result.toString();
        } catch (NumberFormatException e) {
            return "Invalid numeric parameters";
        }
    }

    // Example 5: Using Janino with predefined code templates
    @GetMapping("/good5")
    public String good_case_5(HttpServletRequest request) {
        try {
            String operation = request.getParameter("operation");
            double a = Double.parseDouble(request.getParameter("a"));
            double b = Double.parseDouble(request.getParameter("b"));
            
            // Predefined code templates based on operation
            String codeTemplate;
            switch (operation) {
                case "add": codeTemplate = "return a + b;"; break;
                case "subtract": codeTemplate = "return a - b;"; break;
                case "multiply": codeTemplate = "return a * b;"; break;
                case "divide": codeTemplate = "return a / b;"; break;
                default: return "Invalid operation";
            }
            
            ScriptEvaluator evaluator = new ScriptEvaluator();
            evaluator.setParameters(new String[] { "a", "b" }, new Class[] { double.class, double.class });
            evaluator.setReturnType(double.class);
            
            // ok: java-code-injection
            evaluator.cook(codeTemplate);
            
            Object result = evaluator.evaluate(new Object[] { a, b });
            return "Janino Result: " + result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 6: Using BeanShell with parameter binding instead of direct code execution
    @RequestMapping("/good6")
    public String good_case_6(@RequestParam String operation, @RequestParam double num1, @RequestParam double num2) {
        try {
            Interpreter interpreter = new Interpreter();
            interpreter.set("num1", num1);
            interpreter.set("num2", num2);
            
            // Use a map of predefined expressions
            Map<String, String> safeExpressions = Map.of(
                "add", "return num1 + num2;",
                "subtract", "return num1 - num2;",
                "multiply", "return num1 * num2;",
                "divide", "return num1 / num2;"
            );
            
            if (!safeExpressions.containsKey(operation)) {
                return "Invalid operation";
            }
            
            // ok: java-code-injection
            Object result = interpreter.eval(safeExpressions.get(operation));
            
            return "BeanShell Result: " + (result != null ? result.toString() : "null");
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Example 7: Using AWS Lambda with safe parameter passing
    @GetMapping("/good7")
    public String good_case_7(@RequestParam String operation, @RequestParam double value1, @RequestParam double value2) {
        // Validate operation
        if (!operation.matches("add|subtract|multiply|divide")) {
            return "Invalid operation";
        }
        
        AWSLambda awsLambda = AWSLambdaClientBuilder.defaultClient();
        InvokeRequest request = new InvokeRequest()
            .withFunctionName("calculator-function");
        
        // ok: java-code-injection
        request.withPayload("{\"operation\":\"" + operation + "\",\"value1\":" + value1 + ",\"value2\":" + value2 + "}");
        
        return "Lambda invoked with safe parameters";
    }

    // Example 8: Using Mozilla Rhino with sandboxed context
    @PostMapping("/good8")
    public String good_case_8(@RequestBody Map<String, Object> params) {
        Context context = Context.enter();
        try {
            // Set security restrictions
            context.setOptimizationLevel(-1);
            context.setLanguageVersion(Context.VERSION_ES6);
            context.setGeneratingDebug(false);
            context.setGeneratingSource(false);
            context.setDebugger(null, null);
            
            Scriptable scope = context.initStandardObjects();
            
            // Add validated parameters to scope
            for (Map.Entry<String, Object> entry : params.entrySet()) {
                if (entry.getValue() instanceof Number) {
                    org.mozilla.javascript.ScriptableObject.putProperty(scope, entry.getKey(), entry.getValue());
                }
            }
            
            // Use a predefined script template
            String scriptTemplate = "x * y + z";
            
            // ok: java-code-injection
            Object result = context.evaluateString(scope, scriptTemplate, "SafeScript", 1, null);
            
            return "Rhino Result: " + Context.toString(result);
        } finally {
            Context.exit();
        }
    }

    // Example 9: Using Jython with predefined script templates
    @GetMapping("/good9")
    public String good_case_9(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        double x = Double.parseDouble(request.getParameter("x"));
        double y = Double.parseDouble(request.getParameter("y"));
        
        // Map of predefined Python scripts
        Map<String, String> safeScripts = Map.of(
            "add", "result = x + y",
            "subtract", "result = x - y",
            "multiply", "result = x * y",
            "divide", "result = x / y if y != 0 else 'Cannot divide by zero'"
        );
        
        if (!safeScripts.containsKey(operation)) {
            return "Invalid operation";
        }
        
        PythonInterpreter interpreter = new PythonInterpreter();
        interpreter.set("x", x);
        interpreter.set("y", y);
        
        // ok: java-code-injection
        interpreter.exec(safeScripts.get(operation));
        
        Object result = interpreter.get("result");
        return "Python Result: " + result.toString();
    }

    // Example 10: Using Spring Expression Language (SpEL) with whitelisted expressions
    @RequestMapping("/good10")
    public String good_case_10(@RequestParam String operation, @RequestParam double x, @RequestParam double y) {
        // Map of predefined SpEL expressions
        Map<String, String> safeExpressions = Map.of(
            "add", "x + y",
            "subtract", "x - y",
            "multiply", "x * y",
            "divide", "x / y"
        );
        
        if (!safeExpressions.containsKey(operation)) {
            return "Invalid operation";
        }
        
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("x", x);
        context.setVariable("y", y);
        
        // ok: java-code-injection
        Expression exp = parser.parseExpression(safeExpressions.get(operation));
        
        Object result = exp.getValue(context);
        return "SpEL Result: " + result.toString();
    }

    // Example 11: Using Java EL with predefined expressions
    @GetMapping("/good11")
    public String good_case_11(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        double a = Double.parseDouble(request.getParameter("a"));
        double b = Double.parseDouble(request.getParameter("b"));
        
        // Map of predefined EL expressions
        Map<String, String> safeExpressions = Map.of(
            "add", "${a + b}",
            "subtract", "${a - b}",
            "multiply", "${a * b}",
            "divide", "${a / b}"
        );
        
        if (!safeExpressions.containsKey(operation)) {
            return "Invalid operation";
        }
        
        ExpressionFactory factory = new ExpressionFactoryImpl();
        ELContext context = new javax.el.StandardELContext(factory);
        
        // Set variables in the context
        javax.el.ValueExpression aExpr = factory.createValueExpression(a, double.class);
        javax.el.ValueExpression bExpr = factory.createValueExpression(b, double.class);
        context.getVariableMapper().setVariable("a", aExpr);
        context.getVariableMapper().setVariable("b", bExpr);
        
        // ok: java-code-injection
        ValueExpression ve = factory.createValueExpression(context, safeExpressions.get(operation), Object.class);
        
        Object result = ve.getValue(context);
        return "EL Result: " + result.toString();
    }

    // Example 12: Using Aviator with predefined expressions
    @PostMapping("/good12")
    public String good_case_12(@RequestBody Map<String, String> payload) {
        String operation = payload.get("operation");
        double x = Double.parseDouble(payload.get("x"));
        double y = Double.parseDouble(payload.get("y"));
        
        // Map of predefined Aviator expressions
        Map<String, String> safeExpressions = Map.of(
            "add", "x + y",
            "subtract", "x - y",
            "multiply", "x * y",
            "divide", "x / y"
        );
        
        if (!safeExpressions.containsKey(operation)) {
            return "Invalid operation";
        }
        
        Map<String, Object> env = Map.of("x", x, "y", y);
        
        // ok: java-code-injection
        Object result = AviatorEvaluator.execute(safeExpressions.get(operation), env);
        
        return "Aviator Result: " + result.toString();
    }

    // Example 13: Using Vertx with predefined templates
    public void good_case_13() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/calculate").handler(ctx -> {
            String operation = ctx.request().getParam("operation");
            try {
                double x = Double.parseDouble(ctx.request().getParam("x"));
                double y = Double.parseDouble(ctx.request().getParam("y"));
                
                // Map of predefined expressions
                Map<String, String> safeExpressions = Map.of(
                    "add", "x + y",
                    "subtract", "x - y",
                    "multiply", "x * y",
                    "divide", "x / y"
                );
                
                if (!safeExpressions.containsKey(operation)) {
                    ctx.response().end("Invalid operation");
                    return;
                }
                
                // Create a context with the variables
                Map<String, Object> vars = Map.of("x", x, "y", y);
                
                // ok: java-code-injection
                Object result = MVEL.eval(safeExpressions.get(operation), vars);
                
                ctx.response().end("Result: " + result);
            } catch (NumberFormatException e) {
                ctx.response().end("Invalid numeric parameters");
            }
        });
    }

    // Example 14: Using Jetty with parameter validation
    public static class good_case_14 extends AbstractHandler {
        private static final Pattern OPERATION_PATTERN = Pattern.compile("^(add|subtract|multiply|divide)$");
        
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request,
                          HttpServletResponse response) throws IOException, ServletException {
            String operation = request.getParameter("operation");
            
            response.setContentType("text/html;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            baseRequest.setHandled(true);
            
            // Validate operation
            if (operation == null || !OPERATION_PATTERN.matcher(operation).matches()) {
                response.getWriter().println("Invalid operation");
                return;
            }
            
            try {
                double x = Double.parseDouble(request.getParameter("x"));
                double y = Double.parseDouble(request.getParameter("y"));
                
                // Map of predefined expressions
                Map<String, String> safeExpressions = Map.of(
                    "add", "x + y",
                    "subtract", "x - y",
                    "multiply", "x * y",
                    "divide", "x / y"
                );
                
                // Create a context with the variables
                Map<String, Object> vars = Map.of("x", x, "y", y);
                
                // ok: java-code-injection
                Object result = MVEL.eval(safeExpressions.get(operation), vars);
                
                response.getWriter().println("Result: " + result);
            } catch (NumberFormatException e) {
                response.getWriter().println("Invalid numeric parameters");
            }
        }
    }

    // Example 15: Using Apache Commons EL with predefined expressions
    @RequestMapping("/good15")
    public String good_case_15(@RequestParam String operation, @RequestParam double a, @RequestParam double b) {
        try {
            // Map of predefined EL expressions
            Map<String, String> safeExpressions = Map.of(
                "add", "${a+b}",
                "subtract", "${a-b}",
                "multiply", "${a*b}",
                "divide", "${a/b}"
            );
            
            if (!safeExpressions.containsKey(operation)) {
                return "Invalid operation";
            }
            
            ExpressionEvaluatorImpl evaluator = new ExpressionEvaluatorImpl();
            
            // Create variable resolver
            javax.servlet.jsp.el.VariableResolver variableResolver = new javax.servlet.jsp.el.VariableResolver() {
                @Override
                public Object resolveVariable(String name) {
                    if ("a".equals(name)) return a;
                    if ("b".equals(name)) return b;
                    return null;
                }
            };
            
            // ok: java-code-injection
            Object result = evaluator.evaluate(safeExpressions.get(operation), Object.class, variableResolver, null);
            
            return "Commons EL Result: " + result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
// {/fact}