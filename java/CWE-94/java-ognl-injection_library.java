import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;

import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;

import org.apache.struts2.dispatcher.HttpParameters;
import org.apache.struts2.dispatcher.Parameter;

import com.opensymphony.xwork2.ognl.OgnlUtil;
import com.opensymphony.xwork2.util.ValueStack;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;

import spark.Request;
import spark.Response;
import spark.Route;

import io.javalin.http.Context;
import io.javalin.Javalin;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Body;

import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import ratpack.handling.Context;
import ratpack.handling.Handler;

import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Controller;

import org.apache.commons.ognl.OgnlRuntime;
import org.apache.commons.ognl.Node;

import com.google.common.collect.ImmutableMap;

// Security Issue: OGNL Injection Vulnerability
// This file demonstrates various scenarios where OGNL expressions are evaluated with user input,
// potentially leading to remote code execution or other security issues.

// True Positive Examples (Vulnerable/Insecure Code)

public class OgnlInjectionExamples {

    // Using raw OGNL API with user input from HTTP request
// {fact rule=autoescape-disabled@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String expression = request.getParameter("expression");
            Object root = new Object();
            Map<String, Object> context = new HashMap<>();
            
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, context, root);
            System.out.println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using Struts2 OgnlUtil with user input from HTTP request
    @Controller
    public void bad_case_2(HttpServletRequest request) {
        try {
            String expression = request.getParameter("expr");
            OgnlUtil ognlUtil = new OgnlUtil();
            Object root = new Object();
            
            // ruleid: java-ognl-injection
            Object result = ognlUtil.getValue(expression, new HashMap<>(), root);
            System.out.println("Evaluated: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with Spring MVC and path variable
    @Controller
    @RequestMapping("/api")
    public class bad_case_3 {
        @GetMapping("/evaluate/{expr}")
        @ResponseBody
        public String evaluateExpression(@PathVariable("expr") String expression) {
            try {
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                return "Result: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Using OGNL with Spark framework and query parameter
    public void bad_case_4() {
        spark.Spark.get("/evaluate", (Request request, Response response) -> {
            String expression = request.queryParams("expr");
            try {
                // ruleid: java-ognl-injection
                Object result = Ognl.parseExpression(expression).getValue(new OgnlContext(), new Object());
                return "Evaluated to: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        });
    }

    // Using OGNL with Javalin and request body
    public void bad_case_5() {
        Javalin app = Javalin.create().start(7000);
        app.post("/evaluate", ctx -> {
            String expression = ctx.formParam("expression");
            try {
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                ctx.result("Result: " + result);
            } catch (OgnlException e) {
                ctx.result("Error: " + e.getMessage());
            }
        });
    }

    // Using OGNL with Micronaut and request body
    @Controller("/api")
    public class bad_case_6 {
        @Post("/evaluate")
        public String evaluateOgnl(@Body Map<String, String> payload) {
            try {
                String expression = payload.get("expression");
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                return "Result: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Using OGNL with Vert.x and request parameters
    public void bad_case_7() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/evaluate").handler(ctx -> {
            String expression = ctx.request().getParam("expr");
            try {
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                ctx.response().end("Result: " + result);
            } catch (OgnlException e) {
                ctx.response().end("Error: " + e.getMessage());
            }
        });
    }

    // Using OGNL with Ratpack and query parameters
    public class bad_case_8 implements Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String expression = ctx.getRequest().getQueryParams().get("expr");
            try {
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                ctx.render("Result: " + result);
            } catch (OgnlException e) {
                ctx.render("Error: " + e.getMessage());
            }
        }
    }

    // Using OGNL with Play Framework and form data
    public class bad_case_9 extends Controller {
        public Result evaluateExpression() {
            String expression = play.mvc.Http.Context.current().request().body().asFormUrlEncoded().get("expr")[0];
            try {
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                return ok("Result: " + result);
            } catch (OgnlException e) {
                return badRequest("Error: " + e.getMessage());
            }
        }
    }

    // Using OGNL with Struts2 HttpParameters
    public void bad_case_10(HttpParameters parameters) {
        try {
            Parameter parameter = parameters.get("expression");
            String expression = parameter.getValue();
            
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
            System.out.println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with Apache Commons OGNL
    public void bad_case_11(HttpServletRequest request) {
        try {
            String expression = request.getParameter("expr");
            
            // ruleid: java-ognl-injection
            Node node = org.apache.commons.ognl.Ognl.parseExpression(expression);
            Object result = org.apache.commons.ognl.Ognl.getValue(node, new HashMap<>(), new Object());
            System.out.println("Result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with JSON request body
    @Controller
    @RequestMapping("/api")
    public class bad_case_12 {
        @PostMapping("/evaluate")
        @ResponseBody
        public String evaluateFromJson(@RequestBody Map<String, String> payload) {
            try {
                String expression = payload.get("expression");
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                return "Result: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Using OGNL with HTTP headers
    public void bad_case_13(HttpServletRequest request) {
        try {
            String expression = request.getHeader("X-OGNL-Expression");
            
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
            System.out.println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with cookie value
    public void bad_case_14(HttpServletRequest request) {
        try {
            javax.servlet.http.Cookie[] cookies = request.getCookies();
            String expression = null;
            
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("ognlExpr".equals(cookie.getName())) {
                    expression = cookie.getValue();
                    break;
                }
            }
            
            if (expression != null) {
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                System.out.println("Result: " + result);
            }
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with multipart form data
    @Controller
    @RequestMapping("/api")
    public class bad_case_15 {
        @PostMapping("/evaluate-multipart")
        @ResponseBody
        public String evaluateMultipart(@RequestParam("expression") String expression) {
            try {
                // ruleid: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                return "Result: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Using OGNL with hardcoded safe expression
    public void good_case_1(HttpServletRequest request) {
        try {
            // User input is ignored, using a safe hardcoded expression
            String userInput = request.getParameter("expression");
            String safeExpression = "@java.lang.Math@max(1, 2)";
            
            // ok: java-ognl-injection
            Object result = Ognl.getValue(safeExpression, new HashMap<>(), new Object());
            System.out.println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with whitelisted expressions
    @Controller
    @RequestMapping("/api")
    public class good_case_2 {
        private final Map<String, String> ALLOWED_EXPRESSIONS = ImmutableMap.of(
            "sum", "@java.lang.Math@addExact(#p1, #p2)",
            "max", "@java.lang.Math@max(#p1, #p2)",
            "min", "@java.lang.Math@min(#p1, #p2)"
        );
        
        @GetMapping("/safe-evaluate")
        @ResponseBody
        public String evaluateSafe(@RequestParam("operation") String operation, 
                                  @RequestParam("p1") int p1, 
                                  @RequestParam("p2") int p2) {
            try {
                String expression = ALLOWED_EXPRESSIONS.get(operation);
                if (expression == null) {
                    return "Invalid operation";
                }
                
                Map<String, Object> context = new HashMap<>();
                context.put("p1", p1);
                context.put("p2", p2);
                
                // ok: java-ognl-injection
                Object result = Ognl.getValue(expression, context, new Object());
                return "Result: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Using OGNL with input validation and pattern matching
    public void good_case_3(HttpServletRequest request) {
        try {
            String userInput = request.getParameter("expression");
            
            // Validate input against a safe pattern (only allowing simple property access)
            if (userInput != null && userInput.matches("^[a-zA-Z0-9]+(\\.[a-zA-Z0-9]+)*$")) {
                // ok: java-ognl-injection
                Object result = Ognl.getValue(userInput, new HashMap<>(), new Object());
                System.out.println("Result: " + result);
            } else {
                System.out.println("Invalid expression format");
            }
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with a custom security manager
    public void good_case_4(HttpServletRequest request) {
        try {
            String userInput = request.getParameter("expression");
            
            // Set up a security manager to restrict operations
            SecurityManager originalSecurityManager = System.getSecurityManager();
            System.setSecurityManager(new SecurityManager() {
                @Override
                public void checkExec(String cmd) {
                    throw new SecurityException("Command execution not allowed");
                }
                
                @Override
                public void checkRead(String file) {
                    throw new SecurityException("File reading not allowed");
                }
            });
            
            try {
                // ok: java-ognl-injection
                Object result = Ognl.getValue(userInput, new HashMap<>(), new Object());
                System.out.println("Result: " + result);
            } finally {
                // Restore original security manager
                System.setSecurityManager(originalSecurityManager);
            }
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using OGNL with a custom OgnlContext and class resolver
    public void good_case_5(HttpServletRequest request) {
        try {
            String userInput = request.getParameter("expression");
            
            // Create a custom OgnlContext with a restricted class resolver
            OgnlContext context = (OgnlContext) Ognl.createDefaultContext(null);
            context.setClassResolver(new ognl.DefaultClassResolver() {
                @Override
                public Class classForName(String className, Map context) throws ClassNotFoundException {
                    // Only allow access to safe classes
                    if (className.startsWith("java.lang.") || className.startsWith("java.math.")) {
                        return super.classForName(className, context);
                    }
                    throw new ClassNotFoundException("Access denied to class: " + className);
                }
            });
            
            // ok: java-ognl-injection
            Object result = Ognl.getValue(userInput, context, new Object());
            System.out.println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using Spark with a custom validator for OGNL expressions
    public void good_case_6() {
        spark.Spark.get("/safe-evaluate", (Request request, Response response) -> {
            String expression = request.queryParams("expr");
            
            // Custom validator to check for dangerous patterns
            if (containsDangerousPatterns(expression)) {
                return "Potentially dangerous expression rejected";
            }
            
            try {
                // ok: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                return "Evaluated to: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        });
    }
    
    private boolean containsDangerousPatterns(String expression) {
        String[] dangerousPatterns = {
            "@java.lang.Runtime", "getRuntime", "exec",
            "@java.lang.System", "getProperty", "setProperty",
            "@java.lang.Class", "forName", "getMethod",
            "@java.lang.reflect", "Method", "invoke"
        };
        
        for (String pattern : dangerousPatterns) {
            if (expression != null && expression.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    // Using Javalin with parameterized OGNL expressions
    public void good_case_7() {
        Javalin app = Javalin.create().start(7000);
        app.post("/safe-evaluate", ctx -> {
            String operation = ctx.formParam("operation");
            int p1 = Integer.parseInt(ctx.formParam("p1"));
            int p2 = Integer.parseInt(ctx.formParam("p2"));
            
            // Map user operation to safe expression
            String expression;
            switch (operation) {
                case "add":
                    expression = "#p1 + #p2";
                    break;
                case "subtract":
                    expression = "#p1 - #p2";
                    break;
                case "multiply":
                    expression = "#p1 * #p2";
                    break;
                case "divide":
                    expression = "#p1 / #p2";
                    break;
                default:
                    ctx.result("Unknown operation");
                    return;
            }
            
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("p1", p1);
                context.put("p2", p2);
                
                // ok: java-ognl-injection
                Object result = Ognl.getValue(expression, context, new Object());
                ctx.result("Result: " + result);
            } catch (OgnlException e) {
                ctx.result("Error: " + e.getMessage());
            }
        });
    }

    // Using Micronaut with a custom OGNL expression validator
    @Controller("/api")
    public class good_case_8 {
        private final OgnlExpressionValidator validator = new OgnlExpressionValidator();
        
        @Post("/safe-evaluate")
        public String evaluateOgnlSafely(@Body Map<String, String> payload) {
            try {
                String expression = payload.get("expression");
                
                if (!validator.isValid(expression)) {
                    return "Invalid or potentially dangerous expression";
                }
                
                // ok: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                return "Result: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    private static class OgnlExpressionValidator {
        public boolean isValid(String expression) {
            // Check for null or empty
            if (expression == null || expression.trim().isEmpty()) {
                return false;
            }
            
            // Check for dangerous patterns
            String[] dangerousPatterns = {
                "@", "Runtime", "exec", "System", "getProperty", 
                "Class", "forName", "reflect", "Method", "invoke"
            };
            
            for (String pattern : dangerousPatterns) {
                if (expression.contains(pattern)) {
                    return false;
                }
            }
            
            // Additional validation logic here
            return true;
        }
    }

    // Using Vert.x with a restricted OGNL evaluator
    public void good_case_9() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/safe-evaluate").handler(ctx -> {
            String operation = ctx.request().getParam("operation");
            String p1Str = ctx.request().getParam("p1");
            String p2Str = ctx.request().getParam("p2");
            
            try {
                int p1 = Integer.parseInt(p1Str);
                int p2 = Integer.parseInt(p2Str);
                
                // Use a map of predefined safe expressions
                Map<String, String> safeExpressions = new HashMap<>();
                safeExpressions.put("add", "#p1 + #p2");
                safeExpressions.put("subtract", "#p1 - #p2");
                safeExpressions.put("multiply", "#p1 * #p2");
                safeExpressions.put("divide", "#p1 / #p2");
                
                String expression = safeExpressions.get(operation);
                if (expression == null) {
                    ctx.response().end("Invalid operation");
                    return;
                }
                
                Map<String, Object> context = new HashMap<>();
                context.put("p1", p1);
                context.put("p2", p2);
                
                // ok: java-ognl-injection
                Object result = Ognl.getValue(expression, context, new Object());
                ctx.response().end("Result: " + result);
            } catch (NumberFormatException e) {
                ctx.response().end("Invalid number format");
            } catch (OgnlException e) {
                ctx.response().end("Error: " + e.getMessage());
            }
        });
    }

    // Using Ratpack with a custom OGNL expression builder
    public class good_case_10 implements Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String operation = ctx.getRequest().getQueryParams().get("operation");
            String p1Str = ctx.getRequest().getQueryParams().get("p1");
            String p2Str = ctx.getRequest().getQueryParams().get("p2");
            
            try {
                // Build a safe expression based on the operation
                String expression = buildSafeExpression(operation, p1Str, p2Str);
                if (expression == null) {
                    ctx.render("Invalid operation or parameters");
                    return;
                }
                
                // ok: java-ognl-injection
                Object result = Ognl.getValue(expression, new HashMap<>(), new Object());
                ctx.render("Result: " + result);
            } catch (OgnlException e) {
                ctx.render("Error: " + e.getMessage());
            }
        }
        
        private String buildSafeExpression(String operation, String p1Str, String p2Str) {
            try {
                double p1 = Double.parseDouble(p1Str);
                double p2 = Double.parseDouble(p2Str);
                
                switch (operation) {
                    case "add": return p1 + " + " + p2;
                    case "subtract": return p1 + " - " + p2;
                    case "multiply": return p1 + " * " + p2;
                    case "divide": return p1 + " / " + p2;
                    default: return null;
                }
            } catch (NumberFormatException e) {
                return null;
            }
        }
    }

    // Using Play Framework with a custom OGNL expression sanitizer
    public class good_case_11 extends Controller {
        public Result evaluateExpressionSafely() {
            String expression = play.mvc.Http.Context.current().request().body().asFormUrlEncoded().get("expr")[0];
            
            // Sanitize the expression
            String sanitizedExpression = sanitizeExpression(expression);
            if (sanitizedExpression == null) {
                return badRequest("Invalid or potentially dangerous expression");
            }
            
            try {
                // ok: java-ognl-injection
                Object result = Ognl.getValue(sanitizedExpression, new HashMap<>(), new Object());
                return ok("Result: " + result);
            } catch (OgnlException e) {
                return badRequest("Error: " + e.getMessage());
            }
        }
        
        private String sanitizeExpression(String expression) {
            // Remove potentially dangerous characters and keywords
            if (expression == null) return null;
            
            // Check for dangerous patterns
            if (expression.contains("@") || 
                expression.contains("Runtime") || 
                expression.contains("exec") ||
                expression.contains("System") ||
                expression.contains("Class.forName")) {
                return null;
            }
            
            // Only allow basic arithmetic operations and property access
            if (!expression.matches("^[a-zA-Z0-9\\s\\+\\-\\*\\/\\(\\)\\.\\,\\#]+$")) {
                return null;
            }
            
            return expression;
        }
    }

    // Using Apache Commons OGNL with a custom MemberAccess implementation
    public void good_case_12(HttpServletRequest request) {
        try {
            String expression = request.getParameter("expr");
            
            // Create a custom OgnlContext with restricted MemberAccess
            OgnlContext context = (OgnlContext) Ognl.createDefaultContext(null);
            context.setMemberAccess(new ognl.MemberAccess() {
                @Override
                public Object setup(Map context, Object target, Member member, String propertyName) {
                    return null;
                }
                
                @Override
                public void restore(Map context, Object target, Member member, String propertyName, Object state) {
                    // Do nothing
                }
                
                @Override
                public boolean isAccessible(Map context, Object target, Member member, String propertyName) {
                    // Only allow access to safe methods and properties
                    if (member instanceof Method) {
                        Method method = (Method) member;
                        String methodName = method.getName();
                        String className = method.getDeclaringClass().getName();
                        
                        // Only allow basic math operations
                        return className.equals("java.lang.Math") && 
                               (methodName.equals("max") || 
                                methodName.equals("min") || 
                                methodName.equals("abs"));
                    }
                    return false;
                }
            });
            
            // ok: java-ognl-injection
            Object result = Ognl.getValue(expression, context, new Object());
            System.out.println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    // Using Struts2 with a custom TypeConverter for safe OGNL evaluation
    public void good_case_13(HttpParameters parameters) {
        try {
            Parameter parameter = parameters.get("expression");
            String expression = parameter.getValue();
            
            // Use a custom type converter to ensure safe expressions
            Map<String, Object> context = new HashMap<>();
            context.put("converter", new SafeExpressionConverter());
            
            // Parse and convert the expression before evaluation
            Object parsedExpression = Ognl.parseExpression(expression);
            SafeExpressionConverter converter = (SafeExpressionConverter) context.get("converter");
            String safeExpression = converter.convertToSafeExpression(parsedExpression.toString());
            
            // ok: java-ognl-injection
            Object result = Ognl.getValue(safeExpression, context, new Object());
            System.out.println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }
    
    private static class SafeExpressionConverter {
        public String convertToSafeExpression(String expression) {
            // Remove any potentially dangerous parts
            if (expression.contains("@")) {
                return "''"; // Return empty string for safety
            }
            
            // Only allow basic arithmetic operations
            if (!expression.matches("^[0-9\\s\\+\\-\\*\\/\\(\\)]+$")) {
                return "0"; // Return 0 for safety
            }
            
            return expression;
        }
    }

    // Using OGNL with Spring MVC and a custom expression evaluator
    @Controller
    @RequestMapping("/api")
    public class good_case_14 {
        private final SafeOgnlEvaluator evaluator = new SafeOgnlEvaluator();
        
        @GetMapping("/safe-evaluate")
        @ResponseBody
        public String evaluateExpressionSafely(@RequestParam("expr") String expression) {
            try {
                // ok: java-ognl-injection
                Object result = evaluator.evaluateSafely(expression);
                return "Result: " + result;
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    private static class SafeOgnlEvaluator {
        private final Set<String> allowedExpressions = new HashSet<>();
        
        public SafeOgnlEvaluator() {
            // Pre-populate with allowed expressions
            allowedExpressions.add("1+1");
            allowedExpressions.add("2*2");
            allowedExpressions.add("10/2");
            // Add more safe expressions as needed
        }
        
        public Object evaluateSafely(String expression) throws OgnlException {
            // Only evaluate if it's in the whitelist
            if (!allowedExpressions.contains(expression)) {
                throw new SecurityException("Expression not allowed");
            }
            
            return Ognl.getValue(expression, new HashMap<>(), new Object());
        }
    }

    // Using OGNL with JSON request body and a template-based approach
    @Controller
    @RequestMapping("/api")
    public class good_case_15 {
        private final Map<String, String> expressionTemplates = new HashMap<>();
        
        public good_case_15() {
            // Initialize with safe expression templates
            expressionTemplates.put("sum", "#p1 + #p2");
            expressionTemplates.put("difference", "#p1 - #p2");
            expressionTemplates.put("product", "#p1 * #p2");
            expressionTemplates.put("quotient", "#p1 / #p2");
            expressionTemplates.put("max", "@java.lang.Math@max(#p1, #p2)");
            expressionTemplates.put("min", "@java.lang.Math@min(#p1, #p2)");
        }
        
        @PostMapping("/template-evaluate")
        @ResponseBody
        public String evaluateFromTemplate(@RequestBody Map<String, Object> payload) {
            try {
                String templateName = (String) payload.get("template");
                Number p1 = ((Number) payload.get("p1"));
                Number p2 = ((Number) payload.get("p2"));
                
                String expressionTemplate = expressionTemplates.get(templateName);
                if (expressionTemplate == null) {
                    return "Unknown template";
                }
                
                Map<String, Object> context = new HashMap<>();
                context.put("p1", p1);
                context.put("p2", p2);
                
                // ok: java-ognl-injection
                Object result = Ognl.getValue(expressionTemplate, context, new Object());
                return "Result: " + result;
            } catch (OgnlException e) {
                return "Error: " + e.getMessage();
            }
        }
    }
}
// {/fact}